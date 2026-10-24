import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V2_AzureCipher {
    private static boolean privateReturnsTrue() { return true; }

    public void deleteAzureCipherAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("AZURE_CIPHER_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V2_AzureCipherSink()).applyAzureCipherDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V2_AzureCipherSink {
    public void applyAzureCipherDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
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
}
