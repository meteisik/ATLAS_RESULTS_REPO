import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_SaffronPrism {

    public static String data;

    public static boolean authorized;

    public void deleteSaffronPrismAccount() throws SQLException {
        data = System.getenv("SAFFRON_PRISM_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_SaffronPrismSink()).applySaffronPrismDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_SaffronPrismSink {
    public void applySaffronPrismDeletion() throws SQLException {
        String data = CWE284_P10_V1_SaffronPrism.data;
        boolean authorized = CWE284_P10_V1_SaffronPrism.authorized;
        Connection saffronPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronPrism");
        try {
            PreparedStatement saffronPrismDelete = saffronPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronPrismDelete.setString(1, data);
            saffronPrismDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            saffronPrismConnection.close();
        }
    }
}
