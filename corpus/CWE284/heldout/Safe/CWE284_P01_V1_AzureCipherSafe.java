import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_AzureCipherSafe {

    public void deleteAzureCipherAccount() throws SQLException {
        String data;
        data = System.getenv("AZURE_CIPHER_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection azureCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureCipher");
        try {
            PreparedStatement azureCipherDelete = azureCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azureCipherDelete.setString(1, data);
            if (authorized) {
                azureCipherDelete.executeUpdate();
            }
        } finally {
            azureCipherConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
