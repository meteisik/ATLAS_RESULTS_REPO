import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_RuneRaven {
    private static boolean privateReturnsTrue() { return true; }

    public void deleteRuneRavenAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("RUNE_RAVEN_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_RuneRavenChecker()).isAuthorized(requester);
        Connection runeRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeRaven");
        try {
            PreparedStatement runeRavenDelete = runeRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeRavenDelete.setString(1, data);
            if (authorized) {
                runeRavenDelete.executeUpdate();
            }
        } finally {
            runeRavenConnection.close();
        }
    }
}

class CWE284_P07_V2_RuneRavenChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
