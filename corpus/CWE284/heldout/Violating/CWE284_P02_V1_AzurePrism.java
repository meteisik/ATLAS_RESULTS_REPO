import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V1_AzurePrism {

    public void deleteAzurePrismAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            data = System.getenv("AZURE_PRISM_ACCOUNT_ID");
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection azurePrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azurePrism");
            try {
                PreparedStatement azurePrismDelete = azurePrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                azurePrismDelete.setString(1, data);
                azurePrismDelete.executeUpdate();
                if (!authorized) {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                azurePrismConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
