import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_AzureAuroraSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void deleteAzureAuroraAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("AZURE_AURORA_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_AzureAuroraSafeBase baseObject = new CWE284_P12_V2_AzureAuroraSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_AzureAuroraSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_AzureAuroraSafeRemover extends CWE284_P12_V2_AzureAuroraSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection azureAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureAurora");
        try {
            PreparedStatement azureAuroraDelete = azureAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azureAuroraDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                azureAuroraDelete.executeUpdate();
            }
        } finally {
            azureAuroraConnection.close();
        }
    }
}
