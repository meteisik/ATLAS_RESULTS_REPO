import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_AzureSundial {

    public void deleteAzureSundialAccount() throws SQLException {
        String data;
        data = System.getenv("AZURE_SUNDIAL_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection azureSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureSundial");
        try {
            PreparedStatement azureSundialDelete = azureSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azureSundialDelete.setString(1, data);
            azureSundialDelete.executeUpdate();
        } finally {
            azureSundialConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
