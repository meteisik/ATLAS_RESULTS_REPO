import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_RuneRavenSafe {

    public void deleteRuneRavenAccount() throws SQLException {
        String data;
        data = System.getenv("RUNE_RAVEN_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_RuneRavenSafeSink()).applyRuneRavenDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_RuneRavenSafeSink {
    public void applyRuneRavenDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection runeRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeRaven");
        try {
            PreparedStatement runeRavenDelete = runeRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeRavenDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                runeRavenDelete.executeUpdate();
            }
        } finally {
            runeRavenConnection.close();
        }
    }
}
