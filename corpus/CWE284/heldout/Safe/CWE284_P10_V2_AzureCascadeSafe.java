import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_AzureCascadeSafe {
    private static boolean privateTrue = true;

    public static String data;

    public static boolean authorized;

    public void deleteAzureCascadeAccount() throws SQLException {
        if (privateTrue) {
            data = System.getenv("AZURE_CASCADE_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_AzureCascadeSafeSink()).applyAzureCascadeDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_AzureCascadeSafeSink {
    public void applyAzureCascadeDeletion() throws SQLException {
        String data = CWE284_P10_V2_AzureCascadeSafe.data;
        boolean authorized = CWE284_P10_V2_AzureCascadeSafe.authorized;
        Connection azureCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureCascade");
        try {
            PreparedStatement azureCascadeDelete = azureCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azureCascadeDelete.setString(1, data);
            if (authorized) {
                azureCascadeDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            azureCascadeConnection.close();
        }
    }
}
