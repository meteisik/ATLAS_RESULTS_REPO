import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_AzureSignalSafe {

    public void deleteAzureSignalAccount() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("AZURE_SIGNAL_ACCOUNT_ID");
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_AzureSignalSafeBase baseObject = new CWE284_P12_V2_AzureSignalSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_AzureSignalSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_AzureSignalSafeRemover extends CWE284_P12_V2_AzureSignalSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection azureSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureSignal");
        try {
            PreparedStatement azureSignalDelete = azureSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azureSignalDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                azureSignalDelete.executeUpdate();
            }
        } finally {
            azureSignalConnection.close();
        }
    }
}
