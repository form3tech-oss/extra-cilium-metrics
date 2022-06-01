module github.com/form3tech-oss/extra-cilium-metrics

go 1.15

replace github.com/optiopay/kafka => github.com/optiopay/kafka/v2 v2.1.1

replace github.com/mailru/easyjson => github.com/form3tech-oss/easyjson v0.7.7

require (
	github.com/cilium/cilium v1.8.3
	github.com/prometheus/client_golang v1.7.1
	github.com/sirupsen/logrus v1.4.2
)
