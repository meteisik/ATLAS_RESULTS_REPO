import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_OnyxHarbor {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteOnyxHarborAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_HARBOR_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_OnyxHarborSink()).applyOnyxHarborDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_OnyxHarborSink {
    public void applyOnyxHarborDeletion(CWE284_P09_V1_OnyxHarbor.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection onyxHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxHarbor");
        try {
            PreparedStatement onyxHarborDelete = onyxHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxHarborDelete.setString(1, data);
            onyxHarborDelete.executeUpdate();
        } finally {
            onyxHarborConnection.close();
        }
    }
}
