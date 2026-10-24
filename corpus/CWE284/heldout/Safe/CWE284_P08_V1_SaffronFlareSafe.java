import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_SaffronFlareSafe {

    public void deleteSaffronFlareAccount() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_FLARE_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_SaffronFlareSafeSink()).applySaffronFlareDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_SaffronFlareSafeSink {
    public void applySaffronFlareDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection saffronFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronFlare");
        try {
            PreparedStatement saffronFlareDelete = saffronFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronFlareDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                saffronFlareDelete.executeUpdate();
            }
        } finally {
            saffronFlareConnection.close();
        }
    }
}
