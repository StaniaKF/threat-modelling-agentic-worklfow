sequenceDiagram
    autonumber
    actor User
    participant APIGW as API Gateway
    participant Lambda as Lambda Function
    participant CW as CloudWatch Logs
    participant Dynamo as DynamoDB Table

    User->>APIGW: Sends HTTPS Request
    activate APIGW
    APIGW->>Lambda: Invokes Function (Passes Payload)
    activate Lambda
    Lambda->>CW: Streams Execution Logs
    Lambda->>Dynamo: Updates Table (Put/Update Item)
    Lambda-->>APIGW: Returns Response Payload
    deactivate Lambda
    APIGW-->>User: Returns HTTP Response
    deactivate APIGW