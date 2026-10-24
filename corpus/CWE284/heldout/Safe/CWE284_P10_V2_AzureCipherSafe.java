import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_AzureCipherSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public static String data;

    public static boolean authorized;

    public void deleteAzureCipherAccount() throws SQLException {
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("AZURE_CIPHER_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_AzureCipherSafeSink()).applyAzureCipherDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_AzureCipherSafeSink {
    public void applyAzureCipherDeletion() throws SQLException {
        String data = CWE284_P10_V2_AzureCipherSafe.data;
        boolean authorized = CWE284_P10_V2_AzureCipherSafe.authorized;
        Connection azureCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureCipher");
        try {
            PreparedStatement azureCipherDelete = azureCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azureCipherDelete.setString(1, data);
            if (authorized) {
                azureCipherDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            azureCipherConnection.close();
        }
    }
}
