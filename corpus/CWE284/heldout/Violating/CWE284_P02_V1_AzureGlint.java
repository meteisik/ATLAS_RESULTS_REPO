import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V1_AzureGlint {

    public void deleteAzureGlintAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            data = System.getenv("AZURE_GLINT_ACCOUNT_ID");
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection azureGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureGlint");
            try {
                PreparedStatement azureGlintDelete = azureGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                azureGlintDelete.setString(1, data);
                azureGlintDelete.executeUpdate();
                if (!authorized) {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                azureGlintConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
