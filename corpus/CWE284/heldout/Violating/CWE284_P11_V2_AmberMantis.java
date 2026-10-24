import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V2_AmberMantis {
    private static int privateFive = 5;

    public void deleteAmberMantisAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("AMBER_MANTIS_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V2_AmberMantisSink()).applyAmberMantisDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V2_AmberMantisSink {
    public void applyAmberMantisDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection amberMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberMantis");
        try {
            PreparedStatement amberMantisDelete = amberMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberMantisDelete.setString(1, data);
            if (authorized) {
                amberMantisDelete.executeUpdate();
            }
        } finally {
            amberMantisConnection.close();
        }
    }
}
