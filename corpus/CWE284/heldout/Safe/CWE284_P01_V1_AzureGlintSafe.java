import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_AzureGlintSafe {

    public void deleteAzureGlintAccount() throws SQLException {
        String data;
        data = System.getenv("AZURE_GLINT_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection azureGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureGlint");
        try {
            PreparedStatement azureGlintDelete = azureGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azureGlintDelete.setString(1, data);
            if (authorized) {
                azureGlintDelete.executeUpdate();
            }
        } finally {
            azureGlintConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
