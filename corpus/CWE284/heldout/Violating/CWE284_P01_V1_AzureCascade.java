import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_AzureCascade {

    public void deleteAzureCascadeAccount() throws SQLException {
        String data;
        data = System.getenv("AZURE_CASCADE_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection azureCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureCascade");
        try {
            PreparedStatement azureCascadeDelete = azureCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azureCascadeDelete.setString(1, data);
            azureCascadeDelete.executeUpdate();
        } finally {
            azureCascadeConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
