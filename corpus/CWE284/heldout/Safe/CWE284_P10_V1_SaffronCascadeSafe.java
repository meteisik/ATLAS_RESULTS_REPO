import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_SaffronCascadeSafe {

    public static String data;

    public static boolean authorized;

    public void deleteSaffronCascadeAccount() throws SQLException {
        data = System.getenv("SAFFRON_CASCADE_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_SaffronCascadeSafeSink()).applySaffronCascadeDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_SaffronCascadeSafeSink {
    public void applySaffronCascadeDeletion() throws SQLException {
        String data = CWE284_P10_V1_SaffronCascadeSafe.data;
        boolean authorized = CWE284_P10_V1_SaffronCascadeSafe.authorized;
        Connection saffronCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronCascade");
        try {
            PreparedStatement saffronCascadeDelete = saffronCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronCascadeDelete.setString(1, data);
            if (authorized) {
                saffronCascadeDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            saffronCascadeConnection.close();
        }
    }
}
