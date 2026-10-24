import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_AzurePrismSafe {

    public void deleteAzurePrismAccount() throws SQLException {
        String data;
        data = System.getenv("AZURE_PRISM_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection azurePrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azurePrism");
        try {
            PreparedStatement azurePrismDelete = azurePrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azurePrismDelete.setString(1, data);
            if (authorized) {
                azurePrismDelete.executeUpdate();
            }
        } finally {
            azurePrismConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
