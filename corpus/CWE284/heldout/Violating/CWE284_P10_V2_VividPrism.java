import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_VividPrism {

    public static String data;

    public static boolean authorized;

    public void deleteVividPrismAccount() throws SQLException {
        if (true) {
            data = System.getenv("VIVID_PRISM_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_VividPrismSink()).applyVividPrismDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_VividPrismSink {
    public void applyVividPrismDeletion() throws SQLException {
        String data = CWE284_P10_V2_VividPrism.data;
        boolean authorized = CWE284_P10_V2_VividPrism.authorized;
        Connection vividPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividPrism");
        try {
            PreparedStatement vividPrismDelete = vividPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            vividPrismDelete.setString(1, data);
            vividPrismDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            vividPrismConnection.close();
        }
    }
}
