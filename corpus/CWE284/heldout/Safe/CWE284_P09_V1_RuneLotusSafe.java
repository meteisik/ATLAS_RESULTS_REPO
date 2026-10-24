import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_RuneLotusSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteRuneLotusAccount() throws SQLException {
        String data;
        data = System.getenv("RUNE_LOTUS_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_RuneLotusSafeSink()).applyRuneLotusDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_RuneLotusSafeSink {
    public void applyRuneLotusDeletion(CWE284_P09_V1_RuneLotusSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection runeLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeLotus");
        try {
            PreparedStatement runeLotusDelete = runeLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeLotusDelete.setString(1, data);
            if (authorized) {
                runeLotusDelete.executeUpdate();
            }
        } finally {
            runeLotusConnection.close();
        }
    }
}
