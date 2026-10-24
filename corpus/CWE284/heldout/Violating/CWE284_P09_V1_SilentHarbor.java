import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_SilentHarbor {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteSilentHarborAccount() throws SQLException {
        String data;
        data = System.getenv("SILENT_HARBOR_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_SilentHarborSink()).applySilentHarborDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_SilentHarborSink {
    public void applySilentHarborDeletion(CWE284_P09_V1_SilentHarbor.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection silentHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentHarbor");
        try {
            PreparedStatement silentHarborDelete = silentHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentHarborDelete.setString(1, data);
            silentHarborDelete.executeUpdate();
        } finally {
            silentHarborConnection.close();
        }
    }
}
