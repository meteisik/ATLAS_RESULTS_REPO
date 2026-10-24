import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_AzureSundial {

    private void applyAzureSundialDeletion(String data, boolean authorized) throws SQLException {
        Connection azureSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureSundial");
        try {
            PreparedStatement azureSundialDelete = azureSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azureSundialDelete.setString(1, data);
            if (authorized) {
                azureSundialDelete.executeUpdate();
            }
        } finally {
            azureSundialConnection.close();
        }
    }

    public void deleteAzureSundialAccount() throws SQLException {
        String data;
        data = System.getenv("AZURE_SUNDIAL_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyAzureSundialDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
