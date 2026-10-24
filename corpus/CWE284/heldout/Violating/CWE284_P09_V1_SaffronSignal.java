import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_SaffronSignal {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteSaffronSignalAccount() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_SIGNAL_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_SaffronSignalSink()).applySaffronSignalDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_SaffronSignalSink {
    public void applySaffronSignalDeletion(CWE284_P09_V1_SaffronSignal.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection saffronSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronSignal");
        try {
            PreparedStatement saffronSignalDelete = saffronSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronSignalDelete.setString(1, data);
            saffronSignalDelete.executeUpdate();
        } finally {
            saffronSignalConnection.close();
        }
    }
}
