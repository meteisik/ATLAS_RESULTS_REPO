import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_SaffronGlint {

    public void deleteSaffronGlintAccount() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_GLINT_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_SaffronGlintSink()).applySaffronGlintDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_SaffronGlintSink {
    public void applySaffronGlintDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection saffronGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronGlint");
        try {
            PreparedStatement saffronGlintDelete = saffronGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronGlintDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                saffronGlintDelete.executeUpdate();
            }
        } finally {
            saffronGlintConnection.close();
        }
    }
}
