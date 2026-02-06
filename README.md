# ChangeGuard MCP

A Model Context Protocol (MCP) server for intelligent change management reviews, deployed on AWS Lambda with Bedrock integration.

## Overview

ChangeGuard MCP provides AI-powered change review capabilities through multiple reviewer modes (Principal Engineer, Security Reviewer, FinOps Reviewer, Delivery Manager). It analyzes change plans and provides structured feedback including risk assessment, missing requirements, and actionable recommendations.

## Architecture

- **AWS Lambda**: Hosts the review gate functionality
- **API Gateway**: REST API endpoint for HTTP access
- **Amazon Bedrock**: Claude 3.5 Sonnet v2 for AI-powered suggestions
- **MCP Adapter**: Protocol translation between MCP JSON-RPC and REST API

## Features

- **Multi-Mode Reviews**: Different reviewer perspectives (engineering, security, finance, delivery)
- **Evidence Detection**: Automatically detects rollback plans, test strategies, approvals, etc.
- **Risk Analysis**: AI-generated risk assessments and mitigation suggestions
- **Structured Output**: Consistent JSON responses with verdict, score, and recommendations
- **Caching**: Optional suggestion caching for performance
- **Flexible Output Levels**: Summary, review, or diagnostic detail levels

## Deployment

### Prerequisites

- AWS CLI configured
- Pulumi CLI installed
- Python 3.11+

### Deploy Infrastructure

```bash
cd changeguard-mcp
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
pulumi up
```

### Environment Variables

The Lambda function uses these environment variables:

- `DEFAULT_BEDROCK_REGION`: AWS region for Bedrock (default: ap-southeast-2)
- `DEFAULT_BEDROCK_MODEL_ID`: Bedrock model ID (default: anthropic.claude-3-5-sonnet-20241022-v2:0)

## Usage

### Direct API Call

```bash
curl -X POST https://your-api-gateway-url/prod \
  -H "Content-Type: application/json" \
  -d '{
    "plan": "Deploy new microservice with blue-green deployment",
    "mode": "principal_engineer",
    "enable_llm_suggestions": true,
    "output_level": "diagnostic"
  }'
```

### MCP Integration

Use the MCP adapter to integrate with MCP-compatible clients:

```json
{
  "pushback-mcp": {
    "command": "/path/to/python",
    "args": ["/path/to/mcp_adapter.py"],
    "env": {},
    "disabled": false,
    "autoApprove": []
  }
}
```

## API Reference

### Request Parameters

- `plan` (required): Description of the change being reviewed
- `context` (optional): Additional context about the change
- `mode` (optional): Reviewer mode - `principal_engineer`, `security_reviewer`, `finops_reviewer`, `delivery_manager`
- `strict` (optional): Whether to block on missing evidence (default: true)
- `output_level` (optional): Detail level - `auto`, `summary`, `review`, `diagnostic`
- `enable_llm_suggestions` (optional): Enable AI-powered suggestions (default: true)

### Response Structure

```json
{
  "verdict": "BLOCKED|CONDITIONAL|APPROVED",
  "score_out_of_10": 7,
  "verdict_reason": "Explanation of the verdict",
  "blockers": ["List of blocking issues"],
  "assumptions_to_challenge": ["Key assumptions to validate"],
  "key_risks": ["Identified risks"],
  "required_actions": ["Actions needed before proceeding"],
  "evidence_detected": {
    "has_rollback": true,
    "has_test_plan": false,
    "has_approvals": true
  },
  "suggested_risks": [
    {
      "title": "Risk title",
      "why": "Risk explanation",
      "category": "reliability",
      "anchor": "Reference point"
    }
  ],
  "llm_meta": {
    "enabled": true,
    "provider": "bedrock",
    "model_id": "anthropic.claude-3-5-sonnet-20241022-v2:0",
    "status": "ok"
  }
}
```

## Reviewer Modes

### Principal Engineer
- Focus: Reliability, operability, technical risk
- Emphasizes: Monitoring, runbooks, rollback procedures
- Trade-offs: Extra build time vs. future incidents

### Security Reviewer  
- Focus: Security controls, compliance, audit trails
- Emphasizes: Least privilege, time-bound exceptions
- Trade-offs: Security vs. delivery speed

### FinOps Reviewer
- Focus: Cost optimization, financial impact
- Emphasizes: Measurable savings, cost trade-offs
- Trade-offs: Cost reduction vs. operational overhead

### Delivery Manager
- Focus: Timeline, stakeholder alignment, scope
- Emphasizes: Approvals, dependencies, communication
- Trade-offs: Scope vs. safety controls

## Files

- `__main__.py`: Pulumi infrastructure definition
- `full_lambda.py`: Complete Lambda function with review logic
- `requirements.txt`: Python dependencies
- `.gitignore`: Git ignore patterns (excludes sensitive files)

## Security

- No sensitive information is stored in the repository
- Bedrock model access controlled via IAM roles
- API Gateway has CORS enabled for web access
- Lambda environment variables for configuration

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes and test locally
4. Submit a pull request

## License

This project is licensed under the MIT License.