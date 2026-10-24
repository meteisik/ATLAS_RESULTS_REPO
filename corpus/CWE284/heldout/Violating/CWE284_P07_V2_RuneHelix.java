import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_RuneHelix {

    public void deleteRuneHelixAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("RUNE_HELIX_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_RuneHelixChecker()).isAuthorized(requester);
        Connection runeHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeHelix");
        try {
            PreparedStatement runeHelixDelete = runeHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeHelixDelete.setString(1, data);
            if (authorized) {
                runeHelixDelete.executeUpdate();
            }
        } finally {
            runeHelixConnection.close();
        }
    }
}

class CWE284_P07_V2_RuneHelixChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
