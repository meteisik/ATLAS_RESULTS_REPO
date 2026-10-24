import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_ArcticHelix {

    public void deleteArcticHelixAccount() throws SQLException {
        String data;
        data = System.getenv("ARCTIC_HELIX_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_ArcticHelixBase baseObject = new CWE284_P12_V1_ArcticHelixRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_ArcticHelixBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_ArcticHelixRemover extends CWE284_P12_V1_ArcticHelixBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection arcticHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticHelix");
        try {
            PreparedStatement arcticHelixDelete = arcticHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticHelixDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                arcticHelixDelete.executeUpdate();
            }
        } finally {
            arcticHelixConnection.close();
        }
    }
}
