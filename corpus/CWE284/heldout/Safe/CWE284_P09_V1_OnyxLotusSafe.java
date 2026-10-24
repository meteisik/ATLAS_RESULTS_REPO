import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_OnyxLotusSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteOnyxLotusAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_LOTUS_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_OnyxLotusSafeSink()).applyOnyxLotusDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_OnyxLotusSafeSink {
    public void applyOnyxLotusDeletion(CWE284_P09_V1_OnyxLotusSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection onyxLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxLotus");
        try {
            PreparedStatement onyxLotusDelete = onyxLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxLotusDelete.setString(1, data);
            if (authorized) {
                onyxLotusDelete.executeUpdate();
            }
        } finally {
            onyxLotusConnection.close();
        }
    }
}
