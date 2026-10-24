import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_VividSignal {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteVividSignalAccount() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("VIVID_SIGNAL_ACCOUNT_ID");
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_VividSignalSink()).applyVividSignalDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_VividSignalSink {
    public void applyVividSignalDeletion(CWE284_P09_V2_VividSignal.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection vividSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividSignal");
        try {
            PreparedStatement vividSignalDelete = vividSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            vividSignalDelete.setString(1, data);
            vividSignalDelete.executeUpdate();
        } finally {
            vividSignalConnection.close();
        }
    }
}
