import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_AzureGlintSafe {
    private static boolean privateReturnsTrue() { return true; }

    public static String data;

    public static boolean authorized;

    public void deleteAzureGlintAccount() throws SQLException {
        if (privateReturnsTrue()) {
            data = System.getenv("AZURE_GLINT_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_AzureGlintSafeSink()).applyAzureGlintDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_AzureGlintSafeSink {
    public void applyAzureGlintDeletion() throws SQLException {
        String data = CWE284_P10_V2_AzureGlintSafe.data;
        boolean authorized = CWE284_P10_V2_AzureGlintSafe.authorized;
        Connection azureGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureGlint");
        try {
            PreparedStatement azureGlintDelete = azureGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azureGlintDelete.setString(1, data);
            if (authorized) {
                azureGlintDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            azureGlintConnection.close();
        }
    }
}
