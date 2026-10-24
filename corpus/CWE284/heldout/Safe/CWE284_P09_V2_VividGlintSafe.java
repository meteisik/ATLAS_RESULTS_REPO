import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_VividGlintSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteVividGlintAccount() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("VIVID_GLINT_ACCOUNT_ID");
            break;
        default:
            data = null;
            break;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_VividGlintSafeSink()).applyVividGlintDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_VividGlintSafeSink {
    public void applyVividGlintDeletion(CWE284_P09_V2_VividGlintSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection vividGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividGlint");
        try {
            PreparedStatement vividGlintDelete = vividGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            vividGlintDelete.setString(1, data);
            if (authorized) {
                vividGlintDelete.executeUpdate();
            }
        } finally {
            vividGlintConnection.close();
        }
    }
}
