import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_SaffronGlintSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteSaffronGlintAccount() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_GLINT_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_SaffronGlintSafeSink()).applySaffronGlintDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_SaffronGlintSafeSink {
    public void applySaffronGlintDeletion(CWE284_P09_V1_SaffronGlintSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection saffronGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronGlint");
        try {
            PreparedStatement saffronGlintDelete = saffronGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronGlintDelete.setString(1, data);
            if (authorized) {
                saffronGlintDelete.executeUpdate();
            }
        } finally {
            saffronGlintConnection.close();
        }
    }
}
