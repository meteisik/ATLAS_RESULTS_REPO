import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_RuneKestrel {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteRuneKestrelAccount() throws SQLException {
        String data;
        data = System.getenv("RUNE_KESTREL_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_RuneKestrelSink()).applyRuneKestrelDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_RuneKestrelSink {
    public void applyRuneKestrelDeletion(CWE284_P09_V1_RuneKestrel.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection runeKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeKestrel");
        try {
            PreparedStatement runeKestrelDelete = runeKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeKestrelDelete.setString(1, data);
            runeKestrelDelete.executeUpdate();
        } finally {
            runeKestrelConnection.close();
        }
    }
}
