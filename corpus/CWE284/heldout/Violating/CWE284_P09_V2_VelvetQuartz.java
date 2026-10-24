import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_VelvetQuartz {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteVelvetQuartzAccount() throws SQLException {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("VELVET_QUARTZ_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_VelvetQuartzSink()).applyVelvetQuartzDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_VelvetQuartzSink {
    public void applyVelvetQuartzDeletion(CWE284_P09_V2_VelvetQuartz.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection velvetQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetQuartz");
        try {
            PreparedStatement velvetQuartzDelete = velvetQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetQuartzDelete.setString(1, data);
            velvetQuartzDelete.executeUpdate();
        } finally {
            velvetQuartzConnection.close();
        }
    }
}
