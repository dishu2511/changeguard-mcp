import pulumi
import pulumi_aws as aws
import json
import base64

# Read the full lambda handler
with open("full_lambda.py", "r") as f:
    handler_code = f.read()

# Create IAM role for Lambda
lambda_role = aws.iam.Role("changeguard-lambda-role",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Action": "sts:AssumeRole",
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"}
        }]
    })
)

# Attach basic Lambda execution policy
aws.iam.RolePolicyAttachment("lambda-basic-execution",
    role=lambda_role.name,
    policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
)

# Create policy for Bedrock access
bedrock_policy = aws.iam.Policy("bedrock-access-policy",
    policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "bedrock:InvokeModel",
                "bedrock:InvokeModelWithResponseStream"
            ],
            "Resource": "*"
        }]
    })
)

# Attach Bedrock policy to Lambda role
aws.iam.RolePolicyAttachment("lambda-bedrock-access",
    role=lambda_role.name,
    policy_arn=bedrock_policy.arn
)

# Create Lambda layer with dependencies
lambda_layer = aws.lambda_.LayerVersion("changeguard-dependencies",
    layer_name="changeguard-dependencies",
    code=pulumi.FileArchive("layer"),
    compatible_runtimes=["python3.11"]
)

# Create Lambda function
lambda_function = aws.lambda_.Function("changeguard-mcp-lambda",
    runtime="python3.11",
    code=pulumi.AssetArchive({
        "lambda_function.py": pulumi.StringAsset(handler_code)
    }),
    handler="lambda_function.lambda_handler",
    role=lambda_role.arn,
    timeout=300,
    memory_size=512,
    layers=[lambda_layer.arn],
    environment={
        "variables": {
            "DEFAULT_BEDROCK_REGION": "ap-southeast-2",
            "DEFAULT_BEDROCK_MODEL_ID": "anthropic.claude-3-5-sonnet-20241022-v2:0"
        }
    }
)

# Create API Gateway
api_gateway = aws.apigateway.RestApi("changeguard-api",
    description="API Gateway for ChangeGuard MCP Server"
)

# Create API Gateway resource
api_resource = aws.apigateway.Resource("changeguard-resource",
    rest_api=api_gateway.id,
    parent_id=api_gateway.root_resource_id,
    path_part="{proxy+}"
)

# Create API Gateway method
api_method = aws.apigateway.Method("changeguard-method",
    rest_api=api_gateway.id,
    resource_id=api_resource.id,
    http_method="ANY",
    authorization="NONE"
)

# Create Lambda integration
api_integration = aws.apigateway.Integration("changeguard-integration",
    rest_api=api_gateway.id,
    resource_id=api_resource.id,
    http_method=api_method.http_method,
    integration_http_method="POST",
    type="AWS_PROXY",
    uri=lambda_function.invoke_arn
)

# Create root method for API Gateway
root_method = aws.apigateway.Method("changeguard-root-method",
    rest_api=api_gateway.id,
    resource_id=api_gateway.root_resource_id,
    http_method="ANY",
    authorization="NONE"
)

# Create root integration
root_integration = aws.apigateway.Integration("changeguard-root-integration",
    rest_api=api_gateway.id,
    resource_id=api_gateway.root_resource_id,
    http_method=root_method.http_method,
    integration_http_method="POST",
    type="AWS_PROXY",
    uri=lambda_function.invoke_arn
)

# Deploy API Gateway
api_deployment = aws.apigateway.Deployment("changeguard-deployment",
    rest_api=api_gateway.id,
    stage_name="prod",
    opts=pulumi.ResourceOptions(depends_on=[api_integration, root_integration])
)

# Give API Gateway permission to invoke Lambda
lambda_permission = aws.lambda_.Permission("api-gateway-invoke-lambda",
    statement_id="AllowExecutionFromAPIGateway",
    action="lambda:InvokeFunction",
    function=lambda_function.name,
    principal="apigateway.amazonaws.com",
    source_arn=pulumi.Output.concat(api_gateway.execution_arn, "/*/*")
)

# Export the API Gateway URL
pulumi.export("api_url", pulumi.Output.concat("https://", api_gateway.id, ".execute-api.", aws.get_region().name, ".amazonaws.com/prod"))
