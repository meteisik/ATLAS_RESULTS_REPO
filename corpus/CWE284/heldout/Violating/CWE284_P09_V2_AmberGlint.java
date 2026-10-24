import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_AmberGlint {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteAmberGlintAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("AMBER_GLINT_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_AmberGlintSink()).applyAmberGlintDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_AmberGlintSink {
    public void applyAmberGlintDeletion(CWE284_P09_V2_AmberGlint.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection amberGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberGlint");
        try {
            PreparedStatement amberGlintDelete = amberGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberGlintDelete.setString(1, data);
            amberGlintDelete.executeUpdate();
        } finally {
            amberGlintConnection.close();
        }
    }
}
