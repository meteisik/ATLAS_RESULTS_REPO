import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_SilentLotusSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteSilentLotusAccount() throws SQLException {
        String data;
        data = System.getenv("SILENT_LOTUS_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_SilentLotusSafeSink()).applySilentLotusDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_SilentLotusSafeSink {
    public void applySilentLotusDeletion(CWE284_P09_V1_SilentLotusSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection silentLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentLotus");
        try {
            PreparedStatement silentLotusDelete = silentLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentLotusDelete.setString(1, data);
            if (authorized) {
                silentLotusDelete.executeUpdate();
            }
        } finally {
            silentLotusConnection.close();
        }
    }
}
