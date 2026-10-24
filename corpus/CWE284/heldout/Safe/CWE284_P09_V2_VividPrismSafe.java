import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_VividPrismSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteVividPrismAccount() throws SQLException {
        String data;
        while (true) {
            data = System.getenv("VIVID_PRISM_ACCOUNT_ID");
            break;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_VividPrismSafeSink()).applyVividPrismDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_VividPrismSafeSink {
    public void applyVividPrismDeletion(CWE284_P09_V2_VividPrismSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection vividPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividPrism");
        try {
            PreparedStatement vividPrismDelete = vividPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            vividPrismDelete.setString(1, data);
            if (authorized) {
                vividPrismDelete.executeUpdate();
            }
        } finally {
            vividPrismConnection.close();
        }
    }
}
