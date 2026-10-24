import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V2_AzureSundial {

    public void deleteAzureSundialAccount() throws SQLException {
        String data;
        while (true) {
            data = System.getenv("AZURE_SUNDIAL_ACCOUNT_ID");
            break;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V2_AzureSundialSink()).applyAzureSundialDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V2_AzureSundialSink {
    public void applyAzureSundialDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection azureSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureSundial");
        try {
            PreparedStatement azureSundialDelete = azureSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azureSundialDelete.setString(1, data);
            if (authorized) {
                azureSundialDelete.executeUpdate();
            }
        } finally {
            azureSundialConnection.close();
        }
    }
}
