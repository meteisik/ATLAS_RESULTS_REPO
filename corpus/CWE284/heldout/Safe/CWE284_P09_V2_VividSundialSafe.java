import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_VividSundialSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteVividSundialAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("VIVID_SUNDIAL_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_VividSundialSafeSink()).applyVividSundialDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_VividSundialSafeSink {
    public void applyVividSundialDeletion(CWE284_P09_V2_VividSundialSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection vividSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividSundial");
        try {
            PreparedStatement vividSundialDelete = vividSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            vividSundialDelete.setString(1, data);
            if (authorized) {
                vividSundialDelete.executeUpdate();
            }
        } finally {
            vividSundialConnection.close();
        }
    }
}
