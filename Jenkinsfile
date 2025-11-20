pipeline {
    agent any
    options {
        skipStagesAfterUnstable()
    }
    stages {
        stage('Version') {
            steps {
                sh 'python3 --version'
            }
        }
        /*stage('Run'){
            steps {
                sh 'go run main.go'
            }
        }*/
        stage('Run one more'){
            steps {
                sh 'python3 ./scripts/registr.py vlad pochta@yandex.ru qwerty'
            }
        }
        stage('SonarQube analysis') {
            steps {
                withSonarQubeEnv('SonarCloud') { 
                    sh "/var/lib/jenkins/tools/hudson.plugins.sonar.SonarRunnerInstallation/SonarQube/bin/sonar-scanner"
                }
            }
        }
        stage("Quality Gate") {
            steps {
              timeout(time: 1, unit: 'MINUTES') {
                waitForQualityGate abortPipeline: true
              }
            }
          }

    }
}