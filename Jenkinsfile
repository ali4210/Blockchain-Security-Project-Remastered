pipeline {
    agent any

    environment {
        VAULT_ADDR = 'http://192.168.0.150:8200'
        VAULT_TOKEN = 'cross-vault-6b76c24b1e537ee522d3369651764e94'
        ELASTIC_PASSWORD = 'ElasticAdminPass123'
    }

    stages {
        stage('Vault Secrets Extraction') {
            steps {
                echo '[+] Querying HashiCorp Vault for Dynamic Tokens...'
                sh '''
                    # Fetch SonarQube token from Vault
                    SONAR_TOKEN=$(curl -s -H "X-Vault-Token: ${VAULT_TOKEN}" "${VAULT_ADDR}/v1/secret/data/sonarqube" | jq -r '.data.data.token')
                    echo "SONAR_TOKEN=${SONAR_TOKEN}" > .vault_env
                '''
            }
        }

        stage('SonarQube SAST & Quality Gate') {
            steps {
                echo '[+] Executing SonarScanner Analysis...'
                sh '''
                    source .vault_env
                    docker run --rm --network host -v "$(pwd):/usr/src" \
                      sonarsource/sonar-scanner-cli \
                      -Dsonar.host.url="http://127.0.0.1:9000" \
                      -Dsonar.login="${SONAR_TOKEN}" \
                      -Dsonar.projectKey="blockchain-security-soc" \
                      -Dsonar.sources="contracts,scripts" \
                      -Dsonar.exclusions="out/**,cache/**,node_modules/**,lib/**"
                '''
            }
        }

        stage('Master Security & AI SOC Audit') {
            steps {
                echo '[+] Running Autonomous Multi-Zone Pipeline...'
                sh '''
                    make pipeline-e2e
                '''
            }
        }

        stage('ArgoCD GitOps Promotion') {
            steps {
                echo '[+] Promoting verified deployment to Argo CD...'
                sh '''
                    # Hard refresh Argo CD to deploy latest commit
                    kubectl annotate application blockchain-soc-pipeline -n argocd argocd.argoproj.io/refresh=hard --overwrite || true
                '''
            }
        }
    }

    post {
        always {
            cleanWs()
        }
        success {
            echo '[+] Jenkins Pipeline Completed Successfully. Cluster state reconciled.'
        }
        failure {
            echo '[-] Jenkins Pipeline Failed. Deployment gated.'
        }
    }
}