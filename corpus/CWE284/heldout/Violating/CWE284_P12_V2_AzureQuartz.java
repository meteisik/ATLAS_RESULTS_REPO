import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_AzureQuartz {

    public void deleteAzureQuartzAccount() throws SQLException {
        String data;
        while (true) {
            data = System.getenv("AZURE_QUARTZ_ACCOUNT_ID");
            break;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_AzureQuartzBase baseObject = new CWE284_P12_V2_AzureQuartzRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_AzureQuartzBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_AzureQuartzRemover extends CWE284_P12_V2_AzureQuartzBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection azureQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureQuartz");
        try {
            PreparedStatement azureQuartzDelete = azureQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azureQuartzDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                azureQuartzDelete.executeUpdate();
            }
        } finally {
            azureQuartzConnection.close();
        }
    }
}
