import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_RuneRavenSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteRuneRavenAccount() throws SQLException {
        String data;
        data = System.getenv("RUNE_RAVEN_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_RuneRavenSafeSink()).applyRuneRavenDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_RuneRavenSafeSink {
    public void applyRuneRavenDeletion(CWE284_P09_V1_RuneRavenSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
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
