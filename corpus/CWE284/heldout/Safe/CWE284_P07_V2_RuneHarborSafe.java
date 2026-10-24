import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_RuneHarborSafe {

    public void deleteRuneHarborAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("RUNE_HARBOR_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_RuneHarborSafeChecker()).isAuthorized(data);
        Connection runeHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeHarbor");
        try {
            PreparedStatement runeHarborDelete = runeHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeHarborDelete.setString(1, data);
            if (authorized) {
                runeHarborDelete.executeUpdate();
            }
        } finally {
            runeHarborConnection.close();
        }
    }
}

class CWE284_P07_V2_RuneHarborSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
