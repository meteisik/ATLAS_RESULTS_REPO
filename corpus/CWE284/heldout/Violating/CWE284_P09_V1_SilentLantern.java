import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_SilentLantern {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteSilentLanternAccount() throws SQLException {
        String data;
        data = System.getenv("SILENT_LANTERN_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_SilentLanternSink()).applySilentLanternDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_SilentLanternSink {
    public void applySilentLanternDeletion(CWE284_P09_V1_SilentLantern.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection silentLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentLantern");
        try {
            PreparedStatement silentLanternDelete = silentLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentLanternDelete.setString(1, data);
            silentLanternDelete.executeUpdate();
        } finally {
            silentLanternConnection.close();
        }
    }
}
