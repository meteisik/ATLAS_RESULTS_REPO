import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_RuneKestrel {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void deleteRuneKestrelAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("RUNE_KESTREL_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_RuneKestrelChecker()).isAuthorized(requester);
        Connection runeKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeKestrel");
        try {
            PreparedStatement runeKestrelDelete = runeKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeKestrelDelete.setString(1, data);
            if (authorized) {
                runeKestrelDelete.executeUpdate();
            }
        } finally {
            runeKestrelConnection.close();
        }
    }
}

class CWE284_P07_V2_RuneKestrelChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
