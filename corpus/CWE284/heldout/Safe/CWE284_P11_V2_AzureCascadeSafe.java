import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V2_AzureCascadeSafe {
    private static int privateFive = 5;

    public void deleteAzureCascadeAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("AZURE_CASCADE_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V2_AzureCascadeSafeSink()).applyAzureCascadeDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V2_AzureCascadeSafeSink {
    public void applyAzureCascadeDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection azureCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureCascade");
        try {
            PreparedStatement azureCascadeDelete = azureCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azureCascadeDelete.setString(1, data);
            if (authorized) {
                azureCascadeDelete.executeUpdate();
            }
        } finally {
            azureCascadeConnection.close();
        }
    }
}
