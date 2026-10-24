import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_OnyxComet {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteOnyxCometAccount() throws SQLException {
        String data;
        data = System.getenv("ONYX_COMET_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_OnyxCometSink()).applyOnyxCometDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_OnyxCometSink {
    public void applyOnyxCometDeletion(CWE284_P09_V1_OnyxComet.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection onyxCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxComet");
        try {
            PreparedStatement onyxCometDelete = onyxCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxCometDelete.setString(1, data);
            onyxCometDelete.executeUpdate();
        } finally {
            onyxCometConnection.close();
        }
    }
}
