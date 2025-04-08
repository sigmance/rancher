package common

import (
	"fmt"
	"time"

	"github.com/rancher/rancher/pkg/auth/tokens/hashers"
	clusterv3 "github.com/rancher/rancher/pkg/generated/norman/cluster.cattle.io/v3"
	managementv3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NewClusterAuthToken creates a new cluster auth token from a given token.
// The hashed value is managed separately.
// Does not create the token in the remote cluster.
func NewClusterAuthToken(token *managementv3.Token) (*clusterv3.ClusterAuthToken, error) {
	tokenEnabled := token.Enabled == nil || *token.Enabled
	result := &clusterv3.ClusterAuthToken{
		ObjectMeta: metav1.ObjectMeta{
			Name: token.ObjectMeta.Name,
		},
		TypeMeta: metav1.TypeMeta{
			Kind: "ClusterAuthToken",
		},
		UserName:  token.UserID,
		ExpiresAt: token.ExpiresAt,
		Enabled:   tokenEnabled,
	}
	return result, nil
}

// NewClusterAuthSecret creates a new secret from the given token and its hash value
// The cluster auth token is managed separately.
// Does not create the secret in the remote cluster.
func NewClusterAuthSecret(token *managementv3.Token, hashedValue string) (*corev1.Secret, error) {
	result := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: ClusterAuthSecretName(token.ObjectMeta.Name),
		},
		TypeMeta: metav1.TypeMeta{
			Kind: "Secret",
		},
		Data: map[string][]byte{
			"hash": []byte(hashedValue),
		},
	}
	return result, nil
}

// ClusterAuthSecretName computes the name of the cluster auth secret for a
// token T from the name of T.
func ClusterAuthSecretName(tokenName string) string {
	return "cat-" + tokenName
}

// ClusterAuthSecretValue extracts the token hash stored in the secret.
func ClusterAuthSecretValue(clusterAuthSecret *corev1.Secret) string {
	return string(clusterAuthSecret.Data["hash"])
}

// VerifyClusterAuthToken verifies that a provided secret key is valid for the
// given clusterAuthToken and hashed value.
func VerifyClusterAuthToken(secretKey string,
	clusterAuthToken *clusterv3.ClusterAuthToken,
	clusterAuthSecret *corev1.Secret) error {
	logrus.Warnf("ZZZ cluster-auth-token [%s], SECRET (%s)",
		clusterAuthToken.Name, secretKey)

	if !clusterAuthToken.Enabled {
		logrus.Warnf("ZZZ cluster-auth-token [%s] disabled, FAIL",
			clusterAuthToken.Name)
		return fmt.Errorf("token is not enabled")
	}

	expiresAt := clusterAuthToken.ExpiresAt
	if expiresAt != "" {
		expires, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			logrus.Warnf("ZZZ cluster-auth-token [%s] error (%s), FAIL",
				clusterAuthToken.Name, err)
			return err
		}
		if expires.Before(time.Now()) {
			logrus.Warnf("ZZZ cluster-auth-token [%s] expired (%s), FAIL",
				clusterAuthToken.Name, expiresAt)
			return fmt.Errorf("auth expired at %s", expiresAt)
		}
	}

	hashedValue := ClusterAuthSecretValue(clusterAuthSecret)

	logrus.Warnf("ZZZ cluster-auth-token [%s], SECRET (%s) HASH (%s)",
		clusterAuthToken.Name, secretKey, hashedValue)

	hasher, err := hashers.GetHasherForHash(hashedValue)
	if err != nil {
		logrus.Warnf("ZZZ cluster-auth-token [%s], SECRET (%s) HASH (%s) error (%s) FAIL",
			clusterAuthToken.Name, secretKey, hashedValue, err)

		return fmt.Errorf("unable to get hasher for clusterAuthToken %s/%s, err: %w",
			clusterAuthToken.Name, clusterAuthToken.Namespace, err)
	}

	err = hasher.VerifyHash(hashedValue, secretKey)
	if err != nil {
		logrus.Warnf("ZZZ cluster-auth-token [%s], SECRET (%s) HASH (%s) VERIFY error (%s) FAIL",
			clusterAuthToken.Name, secretKey, hashedValue, err)
	}
	return err
}
