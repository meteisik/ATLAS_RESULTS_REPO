import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V2_AzureMantisSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteAzureMantisAccount() throws SQLException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("AZURE_MANTIS_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V2_AzureMantisSafeSink()).applyAzureMantisDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V2_AzureMantisSafeSink {
    public void applyAzureMantisDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection azureMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureMantis");
        try {
            PreparedStatement azureMantisDelete = azureMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azureMantisDelete.setString(1, data);
            if (authorized) {
                azureMantisDelete.executeUpdate();
            }
        } finally {
            azureMantisConnection.close();
        }
    }
}
